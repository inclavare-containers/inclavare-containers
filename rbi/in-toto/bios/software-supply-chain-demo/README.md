# in-toto demo for bios

This is a demo fork and modified from in-toto demo https://github.com/in-toto/demo. This is used for 
produce a linux kernel `bios-256k.bin`.

### Download and setup in-toto on \*NIX (Linux, OS X, ..)
__Set up Environment__
As `python 3.6.8`

```bash
# install gcc, docker
yum install -y gcc docker

# install rust for cryptography package for python3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
source $HOME/.cargo/env
```

__Get demo files and install in-toto__
```bash
# Fetch the demo repo using git
git clone https://github.com/alibaba/inclavare-containers.git

# Change into the demo directory
cd inclavare-containers/rbi/in-toto/bios/software-supply-chain-demo

# Install a compatible version of in-toto
pip install -r requirements.txt

# Every step has a default timeout 10s, which is too short for a build
# Change it to 1200s
export IN_TOTO_LINK_CMD_EXEC_TIMEOUT='900'
```
*Note: If you are having troubles installing in-toto, make sure you have all
the system dependencies. See the [installation guide on
in-toto.readthedocs.io](https://in-toto.readthedocs.io/en/latest/installing.html)
for details.*

Inside the demo directory you will find four directories: `owner_jerry`,
`functionary_alice`, `functionary_bob` and `final_product`. Jerry, Alice and Bob
already have RSA keys in each of their directories. This is what you see:
```bash
tree  # If you don't have tree, try 'find .' instead
# the tree command gives you the following output
# .
# .
# ├── final_product
# ├── functionary_alice
# │   ├── alice
# │   └── alice.pub
# ├── functionary_bob
# │   ├── bob
# │   └── bob.pub
# ├── owner_jerry
# │   ├── create_layout.py
# │   ├── jerry
# │   └── jerry.pub
# ├── README.md
# ├── requirements.txt
# ├── run_demo_md.py
# └── run_demo.py
```

### Define software supply chain layout (Jerry)
We simplify the software supply chain of kernel.

* Jerry, who is the owner of the supply chain.

* Alice, assigned by Jerry, is in charge of cloning code step named `clone`.

* Bob, assigned by Jerry, is in charge of building step named `build`.

* After `build` step, any client can use pubkey of Jerry, Alice and Bob to verify.

```shell
# Create and sign the software supply chain layout on behalf of Jerry
cd owner_jerry
python create_layout.py
```
The script will create a layout, add Alice's and Bob's public keys (fetched from
their directories), sign it with Jerry's private key and dump it to `root.layout`.
In `root.layout`, you will find that (besides the signature and other information)
there are three steps, `clone` and `build`, that
the functionaries Alice and Bob, identified by their public keys, are authorized
to perform.

### Clone project source code (Alice)
Now, we will take the role of the functionary Bob and perform the step
`clone` on his behalf, that is we use in-toto to clone the project repo from GitHub and
record metadata for what we do. Execute the following commands to change to Bob's
directory and perform the step.

```shell
cd ../functionary_alice
in-toto-run --step-name clone --products inclavare-containers/rbi/bios-256k/Dockerfile \
inclavare-containers/rbi/bios-256k/build-bios.sh \
inclavare-containers/rbi/bios-256k/build-docker-image.sh \
inclavare-containers/rbi/bios-256k/scripts/start.sh --key alice -- git clone https://github.com/alibaba/inclavare-containers.git
```

Here is what happens behind the scenes:
 1. In-toto wraps the command `git clone https://github.com/alibaba/inclavare-containers.git`,
 1. hashes the contents of the source code interested, i.e. `inclavare-containers/rbi/bios/*`,
 1. adds the hash together with other information to a metadata file,
 1. signs the metadata with Alice's private key, and
 1. stores everything to `clone.[Alice's keyid].link`.

### Build (Bob)
Now, we will perform Bob’s `build` step by executing the following commands
to change to Bob's directory and build the
artifact we are interested in.

```shell
cd ../functionary_bob
in-toto-run --step-name build --materials inclavare-containers/rbi/bios-256k/Dockerfile \
inclavare-containers/rbi/bios-256k/build-bios.sh \
inclavare-containers/rbi/bios-256k/build-docker-image.sh \
--products inclavare-containers/rbi/result/bios/bios-256k.bin --key bob -- bash inclavare-containers/rbi/rbi.sh bios
```

This will create another step link metadata file, called `build.[Bob's keyid].link`.
It's time to release our software now.


### Verify final product (client)
Let's first copy all relevant files into the `final_product` that is
our software package `inclavare-containers/rbi/result/bios/bios-256k.bin` , the integrity checking script `inclavare-containers/rbi/misc/check-integrity.sh` and the related metadata files `root.layout`,
`clone.[Alice's keyid].link`, `build.[Bob's keyid].link`:
```shell
cd ..
cp owner_jerry/root.layout functionary_alice/clone.*.link functionary_bob/build.*.link final_product/
mkdir -p final_product/inclavare-containers/rbi/result/bios/
mkdir -p final_product/inclavare-containers/rbi/misc/
cp functionary_bob/inclavare-containers/rbi/result/bios/bios-256k.bin final_product/inclavare-containers/rbi/result/bios/bios-256k.bin
cp functionary_bob/inclavare-containers/rbi/misc/check-integrity.sh final_product/inclavare-containers/rbi/misc/check-integrity.sh
```
And now run verification on behalf of the client:
```shell
cd final_product
# Fetch Jerry's public key from a trusted source to verify the layout signature
# Note: The functionary public keys are fetched from the layout
cp ../owner_jerry/jerry.pub .
in-toto-verify --layout root.layout --layout-key jerry.pub
```
This command will verify that
 1. the layout has not expired,
 2. was signed with Jerry’s private key,
<br>and that according to the definitions in the layout
 3. each step was performed and signed by the authorized functionary
 4. the recorded materials and products follow the artifact rules and
 5. the inspection `integrity` checks whether the product `vmlinux` is as expected.


From it, you will see the meaningful output `PASSING` and a return value
of `0`, that indicates verification worked out well:
```shell
echo $?
# should output 0
```

### Tired of copy-pasting commands?
The same script can be used to sequentially execute all commands listed above. Just change into the `demo` directory, run `python run_demo.py` without flags and observe the output.

```bash
# In the demo directory
python run_demo.py
```

And the software supply chain will be prformed, including the verifying operation.
Output will be like

```plaintext

```