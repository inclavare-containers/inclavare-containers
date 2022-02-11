from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock

SHA256_VALUE = "f5c16c540d89b96b9a9040991d1646b46f90ec1a25fea42bd637dd978a41824b"

def main():
  # Load Jerry's private key to later sign the layout
  key_jerry = interface.import_rsa_privatekey_from_file("jerry")
  # Fetch and load Bob's and Alice's public keys
  # to specify that they are authorized to perform certain step in the layout
  key_alice = interface.import_rsa_publickey_from_file("../functionary_alice/alice.pub")
  key_bob = interface.import_rsa_publickey_from_file("../functionary_bob/bob.pub")
  
  layout = Layout.read({
      "_type": "layout",
      "keys": {
          key_bob["keyid"]: key_bob,
          key_alice["keyid"]: key_alice,
      },
      "steps": [{
          "name": "clone",
          "expected_materials": [],
          "expected_products": [
            ["CREATE", "inclavare-containers/rbi/kernel/Dockerfile"],
            ["CREATE", "inclavare-containers/rbi/kernel/build-docker-image.sh"],
            ["CREATE", "inclavare-containers/rbi/kernel/build-kernel.sh"],
            ["CREATE", "inclavare-containers/rbi/kernel/check-integrity.sh"],
            ["CREATE", "inclavare-containers/rbi/kernel/patch/build-kernel.sh"],
            ["CREATE", "inclavare-containers/rbi/kernel/scripts/start.sh"],
            ["CREATE", "inclavare-containers/rbi/misc/check-integrity.sh"]
          ],
          "pubkeys": [key_alice["keyid"]],
          "expected_command": [
              "git",
              "clone",
              "https://github.com/alibaba/inclavare-containers.git"
          ],
          "threshold": 1,
        },{
          "name": "build",
          "expected_materials": [
            ["MATCH", "inclavare-containers/rbi/kernel/Dockerfile","WITH", "PRODUCTS", "FROM", "clone"],
            ["MATCH", "inclavare-containers/rbi/kernel/build-docker-image.sh","WITH", "PRODUCTS", "FROM", "clone"],
            ["MATCH", "inclavare-containers/rbi/kernel/build-kernel.sh","WITH", "PRODUCTS", "FROM", "clone"],
            ["MATCH", "inclavare-containers/rbi/kernel/check-integrity.sh","WITH", "PRODUCTS", "FROM", "clone"],
            ["MATCH", "inclavare-containers/rbi/kernel/patch/build-kernel.sh","WITH", "PRODUCTS", "FROM", "clone"],
            ["MATCH", "inclavare-containers/rbi/kernel/readme.md","WITH", "PRODUCTS", "FROM", "clone"],
            ["MATCH", "inclavare-containers/rbi/kernel/scripts/start.sh","WITH", "PRODUCTS", "FROM", "clone"]
          ],
          "expected_products": [
              ["CREATE", "inclavare-containers/rbi/result/kernel/vmlinux"],
          ],
          "pubkeys": [key_bob["keyid"]],
          "expected_command": [
              "bash",
              "inclavare-containers/rbi/rbi.sh",
              "kernel",
          ],
          "threshold": 1,
        }],
      "inspect": [{
          "name": "integrity",
          "expected_materials": [
              ["MATCH", "inclavare-containers/rbi/result/kernel/vmlinux", "WITH", "PRODUCTS", "FROM", "build"],
              ["MATCH", "inclavare-containers/rbi/misc/check-integrity.sh", "WITH", "PRODUCTS", "FROM", "clone"],
              ["ALLOW", "jerry.pub"],
              ["ALLOW", "root.layout"],
              ["ALLOW", ".keep"]
          ],
          "expected_products": [
              ["CREATE", "inclavare-containers/rbi/result/kernel/.check_done"],
              # FIXME: See expected_materials above
              ["ALLOW", "jerry.pub"],
              ["ALLOW", "root.layout"],
              ["ALLOW", ".keep"]
          ],
          "run": [
              "bash",
              "inclavare-containers/rbi/misc/check-integrity.sh",
              "inclavare-containers/rbi/result/kernel/vmlinux",
              SHA256_VALUE
          ]
        }],
  })

  metadata = Metablock(signed=layout)

  # Sign and dump layout to "root.layout"
  metadata.sign(key_jerry)
  metadata.dump("root.layout")

if __name__ == '__main__':
  main()
