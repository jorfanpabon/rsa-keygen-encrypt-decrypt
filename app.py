import rsa
import base64

def generateKeys():
    public_key, private_key = rsa.newkeys(1024)
    with open('public.pem', 'wb') as f:
        f.write(public_key.save_pkcs1('PEM'))

    with open('private.pem', 'wb') as f:
        f.write(private_key.save_pkcs1('PEM'))


def encryptmsg(msg_to_encrypt):
    with open("public.pem", 'rb') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    encrypt_message = rsa.encrypt(msg_to_encrypt.encode(), public_key)
    encrypt_message = base64.urlsafe_b64encode(encrypt_message)

    return encrypt_message


def decryptmsg(msg_to_decrypt):
    with open("private.pem", 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())

    msg_to_decrypt_ok = msg_to_decrypt[2:len(msg_to_decrypt)-1].encode('ascii')
    decrypt_message_pre = base64.urlsafe_b64decode(msg_to_decrypt_ok)
    decrypt_message = rsa.decrypt(decrypt_message_pre, private_key)
    decrypt_message = decrypt_message.decode()

    return decrypt_message


def run():
    menu = """
    Which option do you want?

    1. Encrypt message
    2. Decrypt a message

    """

    option = int(input(menu))

    if option == 1:
        modal1 = """
        Enter the message:
        
        """
        msg_to_encrypt = input(modal1)
        msg_encrypt = encryptmsg(msg_to_encrypt)
        print('\n')
        print('#-----Encrypted message-----#')
        print(msg_encrypt)
        print('#---------------------------#')
        print('\n')

    
    elif option == 2:
        modal2 = """
        Enter the encrypt message:
        
        """
        msg_to_decrypt = input(modal2)
        msg_decrypt = decryptmsg(msg_to_decrypt)
        print('\n')
        print('#-----Decrypted message-----#')
        print(msg_decrypt)
        print('#---------------------------#')
        print('\n')
    else:
        print("Ingresa una opción correcta")



if __name__ == "__main__":
    run()