# Secure-Web-Development
An example of a secure-by-design site created with no security libraries. 

# Setup Notes
Clone this repo, go to the project root folder in your terminal, set up your venv with `pip install venv`, create a 
new venv with `venv venv` and install requirements with `pip install -r requirements.txt`.
Run `python create_db.py` to build the database and import the global variables needed to run the server. 

# Usage Notes
Start the server with `python blog.py` from the root folder in your terminal. Connect your browser to 
http://127.0.0.1:5000/ to see the site in action. If you're using 2fa, you will need to ensure 
dsscw2blogacc@gmail.com is whitelisted in your email app, however due to us using Google Mail accounts in the way we 
have, emails may still be restricted. Due to this, you can find copies of any messages that are emailed out by the 
server printed in your server console.

Good luck.

# Credits
Designed by UG-4 - University of East Anglia (CMP) 2020/21