# Bitcoin Payment Protocol Interface

This is a simple application which allows you to interact with the Bitcoin payment protocol manually. It displays all of the information from the protocol and lets you perform the actions that your wallet would otherwise do automatically. This lets you use services that use the payment protocol exclusively without having to switch to a new wallet.

## Running

Install all of the dependencies

    python3 setup.py install
    
Compile the Protobuf descriptors

    sudo apt-get install protobuf-compiler
    protoc --proto_path=lib/ --python_out=lib/ lib/paymentrequest.proto

Use the Text User Interface

    python tui.py

Or use the Graphical User Interface

    python gui.py

## License

This project is Copyright (c) 2017 Andrew Chow under the MIT License.

Parts of this project are taken from Electrum; those are Copyright (c) The Electrum Developers under the MIT License