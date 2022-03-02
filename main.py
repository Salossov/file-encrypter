#!/usr/bin/python
import hashlib
import os
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from Cryptodome.Cipher import AES


class EncryptionTool:
    def __init__(
        self,
        user_file,
        user_key,
        user_salt,
    ):

        # Путь до исходного файла

        self.user_file = user_file

        self.input_file_size = os.path.getsize(self.user_file)
        self.chunk_size = 1024
        self.total_chunks = self.input_file_size // self.chunk_size + 1

        # Конвертирование ключ и "соли" в байты

        self.user_key = bytes(user_key, "utf-8")
        self.user_salt = bytes(user_key[::-1], "utf-8")

        # Получаем расширенеие файла

        self.file_extension = self.user_file.split(".")[-1]

        # Тип хеша

        self.hash_type = "SHA256"

        # Имя зашифрованого файла

        self.encrypt_output_file = (
            ".".join(self.user_file.split(".")[:-1])
            + "."
            + self.file_extension
            + ".encr"
        )

        # Имя разшифрованого файла

        self.decrypt_output_file = self.user_file[:-5].split(".")
        self.decrypt_output_file = (
            ".".join(self.decrypt_output_file[:-1])
            + "_decrypted."
            + self.decrypt_output_file[-1]
        )

        # Словарь для ключа и "соли"

        self.hashed_key_salt = dict()

        # ключ и "соль" в 16 битный хеш

        self.hash_key_salt()

    def read_in_chunks(self, file_object, chunk_size=1024):

        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def encrypt(self):

        # Создаем cipher_object

        cipher_object = AES.new(
            self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"]
        )

        self.abort()  # Перезапись существующего файла

        input_file = open(self.user_file, "rb")
        output_file = open(self.encrypt_output_file, "ab")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file, self.chunk_size):
            encrypted_content = cipher_object.encrypt(piece)
            output_file.write(encrypted_content)
            done_chunks += 1
            yield done_chunks / self.total_chunks * 100

        input_file.close()
        output_file.close()

        # Чистим cipher_object

        del cipher_object

    def decrypt(self):

        #  И еще раз этот же цикл но в обратную сторону

        cipher_object = AES.new(
            self.hashed_key_salt["key"], AES.MODE_CFB, self.hashed_key_salt["salt"]
        )

        self.abort()  # Перезапись существующего файла

        input_file = open(self.user_file, "rb")
        output_file = open(self.decrypt_output_file, "xb")
        done_chunks = 0

        for piece in self.read_in_chunks(input_file):
            decrypted_content = cipher_object.decrypt(piece)
            output_file.write(decrypted_content)
            done_chunks += 1
            yield done_chunks / self.total_chunks * 100

        input_file.close()
        output_file.close()

        # Чистим cipher_object

        del cipher_object

    def abort(self):
        if os.path.isfile(self.encrypt_output_file):
            os.remove(self.encrypt_output_file)
        if os.path.isfile(self.decrypt_output_file):
            os.remove(self.decrypt_output_file)

    def hash_key_salt(self):

        # --- Ключ в хеш
        #  Делаем новый "хеш объект"

        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_key)
        self.hashed_key_salt["key"] = bytes(hasher.hexdigest()[:32], "utf-8")

        # Чистим

        del hasher

        # --- Ключ в хеш
        #  Делаем новый "хеш объект"

        hasher = hashlib.new(self.hash_type)
        hasher.update(self.user_salt)
        self.hashed_key_salt["salt"] = bytes(hasher.hexdigest()[:16], "utf-8")

        # Чистим

        del hasher


class MainWindow:

    """GUI Wrapper"""

    # configure root directory path relative to this file

    THIS_FOLDER_G = ""
    if getattr(sys, "frozen", False):

        # frozen

        THIS_FOLDER_G = os.path.dirname(sys.executable)
    else:

        # unfrozen

        THIS_FOLDER_G = os.path.dirname(os.path.realpath(__file__))

    def __init__(self, root):
        self.root = root
        self._cipher = None
        self._file_url = tk.StringVar()
        self._secret_key = tk.StringVar()
        self._secret_key_check = tk.StringVar()
        self._salt = tk.StringVar()
        self._status = tk.StringVar()
        self._status.set("---")

        self.should_cancel = False

        root.title("FileEncrypter by APLYT")
        root.configure(bg="#333333")

        try:
            icon_img = tk.Image(
                "photo", file=self.THIS_FOLDER_G + "./bin/icon.ico"
            )
            root.call("wm", "iconphoto", root._w, icon_img)
        except Exception:
            pass

        self.menu_bar = tk.Menu(root, bg="#333333", relief=tk.FLAT)
        self.menu_bar.add_command(label="Помогите!", command=self.show_help_callback)
        self.menu_bar.add_command(label="О программе", command=self.show_about)

        root.configure(menu=self.menu_bar)

        self.file_entry_label = tk.Label(
            root,
            text="Введите путь у файлу Или на кнопку (Выбрать файл)",
            bg="#333333",
            anchor=tk.W,
        )
        self.file_entry_label.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=0,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.file_entry = tk.Entry(
            root,
            textvariable=self._file_url,
            bg="#333333",
            exportselection=0,
            relief=tk.FLAT,
        )
        self.file_entry.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=1,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.select_btn = tk.Button(
            root,
            text="Выбрать файл",
            command=self.selectfile_callback,
            width=42,
            bg="#3498db",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        self.select_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=2,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry_label1 = tk.Label(
            root,
            text="Введите пароль (НЕОБХОДИМО ЗАПОМНИТЬ, БЕЗ НЕГО НЕЛЬЗЯ РАЗШИФРОВАТЬ ФАЙЛ)",
            bg="#333333",
            anchor=tk.W,
        )
        self.key_entry_label1.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=3,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry1 = tk.Entry(
            root,
            textvariable=self._secret_key,
            bg="#333333",
            exportselection=0,
            relief=tk.FLAT,
        )
        self.key_entry1.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=4,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry_label2 = tk.Label(
            root, text="Повторите пароль (Проверка)", bg="#333333", anchor=tk.W
        )
        self.key_entry_label2.grid(
            padx=12,
            pady=(8, 0),
            ipadx=0,
            ipady=1,
            row=5,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.key_entry2 = tk.Entry(
            root,
            textvariable=self._secret_key_check,
            bg="#333333",
            exportselection=0,
            relief=tk.FLAT,
        )
        self.key_entry2.grid(
            padx=15,
            pady=6,
            ipadx=8,
            ipady=8,
            row=6,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.encrypt_btn = tk.Button(
            root,
            text="ЗАШИФРОВАТЬ",
            command=self.e_check_callback,
            bg="#27ae60",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        self.encrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.decrypt_btn = tk.Button(
            root,
            text="РАЗШИФРОВАТЬ",
            command=self.d_check_callback,
            bg="#27ae60",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        self.decrypt_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=7,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.reset_btn = tk.Button(
            root,
            text="ОЧИСТИТЬ ПОЛЯ",
            command=self.reset_callback,
            bg="#717d7e",
            fg="#ffffff",
            bd=2,
            relief=tk.FLAT,
        )
        self.reset_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=8,
            column=0,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.stop_btn = tk.Button(
            root,
            text="СТОП",
            command=self.cancel_callback,
            bg="#aaaaaa",
            fg="#ffffff",
            bd=2,
            state="disabled",
            relief=tk.FLAT,
        )
        self.stop_btn.grid(
            padx=15,
            pady=8,
            ipadx=24,
            ipady=6,
            row=8,
            column=2,
            columnspan=2,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        self.status_label = tk.Label(
            root,
            textvariable=self._status,
            bg="#333333",
            anchor=tk.W,
            justify=tk.LEFT,
            relief=tk.FLAT,
            wraplength=350,
        )
        self.status_label.grid(
            padx=12,
            pady=(0, 12),
            ipadx=0,
            ipady=1,
            row=9,
            column=0,
            columnspan=4,
            sticky=tk.W + tk.E + tk.N + tk.S,
        )

        tk.Grid.columnconfigure(root, 0, weight=1)
        tk.Grid.columnconfigure(root, 1, weight=1)
        tk.Grid.columnconfigure(root, 2, weight=1)
        tk.Grid.columnconfigure(root, 3, weight=1)

    def selectfile_callback(self):
        try:
            name = filedialog.askopenfile()
            self._file_url.set(name.name)
        except Exception as e:
            self._status.set(e)
            self.status_label.update()

    def freeze_controls(self):
        self.file_entry.configure(state="disabled")
        self.key_entry1.configure(state="disabled")
        self.key_entry2.configure(state="disabled")
        self.select_btn.configure(state="disabled", bg="#aaaaaa")
        self.encrypt_btn.configure(state="disabled", bg="#aaaaaa")
        self.decrypt_btn.configure(state="disabled", bg="#aaaaaa")
        self.reset_btn.configure(state="disabled", bg="#aaaaaa")
        self.stop_btn.configure(state="normal", bg="#e74c3c")
        self.status_label.update()

    def unfreeze_controls(self):
        self.file_entry.configure(state="normal")
        self.key_entry1.configure(state="normal")
        self.key_entry2.configure(state="normal")
        self.select_btn.configure(state="normal", bg="#3498db")
        self.encrypt_btn.configure(state="normal", bg="#27ae60")
        self.decrypt_btn.configure(state="normal", bg="#27ae60")
        self.reset_btn.configure(state="normal", bg="#717d7e")
        self.stop_btn.configure(state="disabled", bg="#aaaaaa")
        self.status_label.update()

    def e_check_callback(self):

        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo("FileEncrypt", "Проверте путь к файлу !!")
            return

        if len(self._secret_key.get()) == 0:
            messagebox.showinfo("FileEncrypt", "Впишите пароль !!")
            return
        elif self._secret_key.get() != self._secret_key_check.get():
            messagebox.showinfo("FileEncrypt", "Пароли не совпадают !!")
            return

        self.encrypt_callback()

    def d_check_callback(self):

        newPath = Path(self._file_url.get())
        if newPath.is_file():
            pass
        else:
            messagebox.showinfo("FileEncrypt", "Проверте путь к файлу !!")
            return

        if self._file_url.get()[-4:] != "encr":
            messagebox.showinfo(
                "FileEncrypt",
                """Этот файл не зашифрован !!
Выберете зашифрованый файл для разшифровки.""",
            )
            return

        if len(self._secret_key.get()) == 0:
            messagebox.showinfo("FileEncrypt", "Впишите пароль !!")
            return
        elif self._secret_key.get() != self._secret_key_check.get():
            messagebox.showinfo("FileEncrypt", "Пароли не совпадают !!")
            return

        self.decrypt_callback()

    def encrypt_callback(self):
        t1 = threading.Thread(target=self.encrypt_execute)
        t1.start()

    def encrypt_execute(self):
        self.freeze_controls()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(), self._secret_key.get(), self._salt.get()
            )
            for percentage in self._cipher.encrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()

            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Операция отменена пользователем !!")
                messagebox.showinfo("FileEncrypt", "Операция отменена пользователем !!")
                self._cipher = None
                self.should_cancel = False
                self.unfreeze_controls()
                return

            self._cipher = None
            self.should_cancel = False
            self._status.set("Файл успешно зашифрован !!")
            messagebox.showinfo("FileEncrypt", "Файл успешно зашифрован !!")
        except Exception as e:

            self._status.set(e)

        self.unfreeze_controls()

    def decrypt_callback(self):
        t2 = threading.Thread(target=self.decrypt_execute)
        t2.start()

    def decrypt_execute(self):
        self.freeze_controls()

        try:
            self._cipher = EncryptionTool(
                self._file_url.get(), self._secret_key.get(), self._salt.get()
            )
            for percentage in self._cipher.decrypt():
                if self.should_cancel:
                    break
                percentage = "{0:.2f}%".format(percentage)
                self._status.set(percentage)
                self.status_label.update()

            if self.should_cancel:
                self._cipher.abort()
                self._status.set("Операция отменена пользователем !!")
                messagebox.showinfo("FileEncrypt", "Операция отменена пользователем !!")
                self._cipher = None
                self.should_cancel = False
                self.unfreeze_controls()
                return

            self._cipher = None
            self.should_cancel = False
            self._status.set("Файл разшифрован !!")
            messagebox.showinfo("FileEncrypt", "Файл разшифрован !!")
        except Exception as e:

            self._status.set(e)

        self.unfreeze_controls()

    def reset_callback(self):
        self._cipher = None
        self._file_url.set("")
        self._secret_key.set("")
        self._salt.set("")
        self._status.set("---")

    def cancel_callback(self):
        self.should_cancel = True

    def show_help_callback(self):
        messagebox.showinfo(
            "Tutorial",
            """1. Откройте приложение и нажмите на кнопку «Выбрать файл» для выбрать файла, например "something.docx" (Или впишите путь к файлу в поле рядом с кнопкой)
2. Введите пароль (только английские символы, цифры и спец. знаки). Запомните его для расшифровки файла потом (в противном случаие вы ПОТЕРЯЕЕТЕ СВОЙ ФАЙЛ НАВСЕГДА)
3. Нажмите кнопку «Зашифровать», чтобы зашифровать файл. Новый зашифрованный файл с расширением ".fencr", например " something.docx.fencr", будет создан в том же каталоге, где находится " something.docx ".
4. Когда вы хотите расшифровать файл, вы выбираете файл с расширением ".fencr" и вводите свой пароль, который вы выбираете во время шифрования. Нажмите кнопку «Расшифровать», чтобы расшифровать. Расшифрованный файл будет иметь то же имя, что и раньше, с суффиксом " decrypted ", например, для " something_decrypted.docx".
5. Нажмите кнопку «Очистить», чтобы сбросить поля ввода и строку состояния.""",
        )

    def show_about(self):
        messagebox.showinfo(
            "FileEncrypt v1.0",
            """FileEncrypt это Инструмент Шифрования Файлов, основанный на алгоритме шифрования AES.
""",
        )


if __name__ == "__main__":
    ROOT = tk.Tk()
    MAIN_WINDOW = MainWindow(ROOT)
    bundle_dir = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
    ROOT.resizable(height=False, width=False)
    ROOT.mainloop()
