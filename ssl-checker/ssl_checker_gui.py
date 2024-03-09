from __future__ import annotations
import tkinter as tk
from tkinter import messagebox as tk_messagebox
from tkinter import ttk
from ssl_checker import get_supported_protocol_cipher_combinations, get_openssl_version
from threading import Thread
from collections import defaultdict
import functools
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    dsa,
    dh,
    ec,
    ed25519,
    ed448,
    x25519,
    x448,
    types,
)


def is_valid_port(port: str) -> bool:
    return port.isdigit() and 0 <= int(port) <= 65535


def show_openssl_version_message() -> None:
    openssl_version = get_openssl_version()
    tk_messagebox.showinfo("OpenSSL Version", openssl_version)


def select_all_callback(event: tk.Event[tk.Entry]) -> None:
    event.widget.select_range(0, "end")
    event.widget.icursor("end")


def copy_treeview_value_callback(
    _event: tk.Event[ttk.Treeview],
    *,
    tree: ttk.Treeview,
    id_to_value_map: dict[str, str],
) -> None:
    selected_id = tree.selection()[0]
    value = id_to_value_map.get(selected_id)
    if value is not None:
        set_clipboard(value)


def set_clipboard(value: str) -> None:
    root.clipboard_clear()
    root.clipboard_append(value)
    root.update()


def certificate_popup(cert_info: dict[str, dict[str, str]], pem_str: str) -> tk.Tk:
    # Configure the popup's root
    popup_root = tk.Tk()
    popup_root.title("Certificate Details")
    popup_root.minsize(width=640, height=640)
    popup_root.rowconfigure(1, weight=1)
    popup_root.columnconfigure(0, weight=1)
    # Configure the Copy Certificate button
    pem_button = ttk.Button(
        popup_root,
        text="Copy Certificate (PEM)",
        command=lambda: set_clipboard(pem_str),
    )
    # Configure popup's treeview
    popup_tree = ttk.Treeview(popup_root, columns=("value",))
    popup_tree.column("#0", stretch=False)
    # Populate the popup's tree
    id_to_value_map = {}
    for category_str, category_data in cert_info.items():
        category_id = popup_tree.insert("", "end", text=category_str)
        for name, value in category_data.items():
            value_repr = value if len(value) <= 48 else value[:45] + "..."
            leaf_id = popup_tree.insert(
                category_id, "end", text=name, values=(value_repr,)
            )
            id_to_value_map[leaf_id] = value
    # Place the widgets
    pem_button.grid(column=0, row=0, pady=(10, 0), sticky=tk.EW)
    popup_tree.grid(column=0, row=1, pady=(10, 0), sticky=tk.NSEW)
    popup_tree.bind(
        "<Double-1>",
        functools.partial(
            copy_treeview_value_callback,
            tree=popup_tree,
            id_to_value_map=id_to_value_map,
        ),
    )
    return popup_root


def extract_key_info(
    public_key: types.CertificatePublicKeyTypes,
) -> dict[str, str] | None:
    if isinstance(public_key, rsa.RSAPublicKey):
        rsa_nums = public_key.public_numbers()
        return {
            "Key Size": str(public_key.key_size),
            "e": str(rsa_nums.e),
            "n": str(rsa_nums.n),
        }
    if isinstance(public_key, dsa.DSAPublicKey):
        dsa_nums = public_key.public_numbers()
        return {
            "Key Size": str(public_key.key_size),
            "y": str(dsa_nums.y),
            "p": str(dsa_nums.parameter_numbers.p),
            "q": str(dsa_nums.parameter_numbers.q),
            "g": str(dsa_nums.parameter_numbers.g),
        }
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        ec_nums = public_key.public_numbers()
        return {
            "Key Size": str(public_key.key_size),
            "Curve": str(ec_nums.curve.name),
            "x": str(ec_nums.x),
            "y": str(ec_nums.y),
        }
    if isinstance(public_key, dh.DHPublicKey):
        dh_nums = public_key.public_numbers()
        return {
            "Key Size": str(public_key.key_size),
            "y": str(dh_nums.y),
            "p": str(dh_nums.parameter_numbers.p),
            "q": str(dh_nums.parameter_numbers.q),
            "g": str(dh_nums.parameter_numbers.g),
        }
    if isinstance(
        public_key,
        (
            ed25519.Ed25519PublicKey,
            ed448.Ed448PublicKey,
            x25519.X25519PublicKey,
            x448.X448PublicKey,
        ),
    ):
        # No public numbers to report
        return None
    return None


def show_cert_details(
    _event: tk.Event[ttk.Treeview],
    *,
    tree_id_map: dict[str, tuple[str, str]],
    supported: dict[tuple[str, str], x509.Certificate],
) -> None:
    selected_id = checked_tree.selection()[0]
    protocol_cipher = tree_id_map.get(selected_id)
    if protocol_cipher is None:
        return
    cert = supported.get(protocol_cipher)
    if cert is None:
        return

    cert_info = {
        "Issuer": {attr.oid._name: str(attr.value) for attr in cert.issuer},
        "Subject": {attr.oid._name: str(attr.value) for attr in cert.subject},
        "Validity": {
            "Valid From": str(cert.not_valid_before_utc),
            "Valid Until": str(cert.not_valid_after_utc),
        },
    }
    key_info = extract_key_info(cert.public_key())
    if key_info is not None:
        cert_info["Key Info"] = key_info
    pem_str = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("utf-8")
    certificate_popup(cert_info, pem_str).mainloop()


def clear_checked_tree() -> None:
    for i in checked_tree.get_children():
        checked_tree.delete(i)


def set_checked_tree(
    supported: dict[tuple[str, str], x509.Certificate],
    unsupported: list[tuple[str, str]],
) -> None:
    # Prepare the data in a tree-like format
    checked_tree_data: dict[bool, dict[str, list[str]]] = {
        True: defaultdict(list),
        False: defaultdict(list),
    }
    for protocol, cipher in supported:
        checked_tree_data[True][protocol].append(cipher)
    for protocol, cipher in unsupported:
        checked_tree_data[False][protocol].append(cipher)

    # Insert the data into our view
    tree_id_map = {}
    for is_supported, data in checked_tree_data.items():
        supported_str = "Supported" if is_supported else "Unsupported"
        support_kind_id = checked_tree.insert("", "end", text=supported_str)
        for protocol, ciphers in data.items():
            protocol_id = checked_tree.insert(support_kind_id, "end", text=protocol)
            for cipher in ciphers:
                leaf_id = checked_tree.insert(protocol_id, "end", text=cipher)
                tree_id_map[leaf_id] = (protocol, cipher)

    checked_tree_callback = functools.partial(
        show_cert_details, tree_id_map=tree_id_map, supported=supported
    )
    checked_tree.bind("<Double-1>", checked_tree_callback)


def check_supported() -> None:
    check_button.config(state=tk.DISABLED)
    host_entry.config(state=tk.DISABLED)
    port_entry.config(state=tk.DISABLED)
    progressbar.start()

    try:
        # Get the list of supported protocols
        host = host_strvar.get()
        port = int(port_strvar.get())
        supported, unsupported = get_supported_protocol_cipher_combinations(host, port)
        # Update the tree view
        clear_checked_tree()
        set_checked_tree(supported, unsupported)
    except Exception as exc:
        tk_messagebox.showerror("Error", "Unexpected error:\n" + str(exc))
        clear_checked_tree()

    progressbar.stop()
    port_entry.config(state=tk.NORMAL)
    host_entry.config(state=tk.NORMAL)
    check_button.config(state=tk.NORMAL)


root = tk.Tk()
root.title("SSL/TLS Checker")
root.minsize(width=360, height=480)
root.rowconfigure(0, weight=1)
root.columnconfigure(0, weight=1)

# Register the validation functions
validate_port = root.register(is_valid_port)
# Declare the StringVars
host_strvar = tk.StringVar(root, value="www.google.com")
port_strvar = tk.StringVar(root, value="443")

# Create the main frame
main_frame = ttk.Frame(root)
main_frame.rowconfigure(4, weight=1)
main_frame.columnconfigure(1, weight=1)
main_frame.grid(sticky=tk.NSEW)
# Create the widgets
host_label = ttk.Label(main_frame, text="Host:")
host_entry = ttk.Entry(main_frame, textvariable=host_strvar)
port_label = ttk.Label(main_frame, text="Port:")
port_entry = ttk.Entry(
    main_frame,
    textvariable=port_strvar,
    validate="key",
    validatecommand=(validate_port, "%P"),
)
check_button = ttk.Button(
    main_frame, text="Check", command=lambda: Thread(target=check_supported).start()
)
progressbar = ttk.Progressbar(main_frame, mode="indeterminate")
checked_tree = ttk.Treeview(main_frame)
options_button = ttk.Button(
    main_frame, text="OpenSSL Version", command=show_openssl_version_message
)
# Place the widgets
host_label.grid(column=0, row=0)
host_entry.grid(column=1, row=0, sticky=tk.EW)
port_label.grid(column=0, row=1)
port_entry.grid(column=1, row=1, sticky=tk.EW)
check_button.grid(column=0, columnspan=2, row=2, pady=(10, 0), sticky=tk.EW)
progressbar.grid(column=0, columnspan=2, row=3, pady=(5, 0), sticky=tk.EW)
checked_tree.grid(column=0, columnspan=2, row=4, pady=(10, 0), sticky=tk.NSEW)
options_button.grid(column=1, row=5, pady=(10, 0), sticky=tk.E)
# Make ctrl+a select all for the entries
host_entry.bind("<Control-KeyRelease-a>", select_all_callback)
port_entry.bind("<Control-KeyRelease-a>", select_all_callback)

root.mainloop()
