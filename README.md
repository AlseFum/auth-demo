this is depend on auth demo.md
file structure
data
    here is all backup files
src
    Key.py:key manager, do rotations, distribute new keys, refresh old keys usage.
    Database.py: store things into sheets, and everysheets store in its own way.
    Server.py:this is where backend API starts
    Util.py:some cryption, and util functions go here
    Cli.py: this file is client-side cli tool. user use this to send things, receive things.it should be a repl,if python cli.py --repl