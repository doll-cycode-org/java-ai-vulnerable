const express = require("express");
const allowControlOrigin = "*"
const PORT = process.env.PORT || 3001;
var database = require('./mongo.js');
const app = express();
const databaseInventory = 'inventory';
//setup connection for mongoDB
//eventually change the URL to be an env var or something a bit more generic
var MongoClient = require('mongodb').MongoClient;
var apiToken = "asc39djnao21mndna2";
//kubernetes cluster connectionstring
var url = "mongodb://admin:password@database.default.svc.cluster.local:27017";


//localhost connectionstring
//var url = "mongodb://localhost:27017";



app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});

app.get("/", (req, res) => {
  res.sendStatus(200);
});

//begin the get requests! Below should correspond to every button in the front-end
//within each 'get' set the appropriate access control header - this is a variable at the top of the script -
// from there construct the mongo client and fill in query informationm, after recieving the response close the connection and grab and respond with the relevant data
app.get("/home", (req, res) => {
  console.log("Request to the home endpoint");
  res.set('Access-Control-Allow-Origin', allowControlOrigin);
  MongoClient.connect(url, function(err, client) {
     if (err) throw err;
     db = client.db()
     var query = { "page": "home" };

    db.collection(databaseInventory).find(query).toArray(function(err, result) {
       if (err) throw err;
       client.close();
       if(result[0] != undefined) {
         res.json({
           generalText: result[0].generalText,
           projectText: result[0].projectText,
           codeText: result[0].codeText,
           additonalText: result[0].additonalText
         });
       } else {
            res.json({
            generalText: "Home",
            projectText: "There was some issue retrieving information from the database :( ",
            codeText: "",
            additonalText: ""
          });
        }
    });
  });
});

app.get("/contact", (req, res) => {
  console.log("Request to the contact endpoint");
  res.set('Access-Control-Allow-Origin', allowControlOrigin);
  MongoClient.connect(url, function(err, client) {
     if (err) throw err;
     db = client.db()
     var query = { page: "contact" };
     var result = db.collection(databaseInventory).find(query).toArray(function(err, result) {
       if (err) throw err;
       client.close();
       if(result[0] != undefined) {
         res.json({
           generalText: result[0].generalText,
           projectText: result[0].projectText,
           codeText: result[0].codeText,
           additonalText: result[0].additonalText
         });
       } else {
         res.json({
           generalText: "contact",
           projectText: "There was some issue retrieving information from the database :( ",
           codeText: "",
           additonalText: ""
         });
       }
    });
  });
});

app.get("/webscraper", (req, res) => {
  console.log("Request to the webscraper endpoint");
  res.set('Access-Control-Allow-Origin', allowControlOrigin);
  MongoClient.connect(url, function(err, client) {
     if (err) throw err;
     db = client.db()
     var query = { page: "webscraper" };
     var result = db.collection(databaseInventory).find(query).toArray(function(err, result) {
       if (err) throw err;
       client.close();
       if(result[0] != undefined) {
         res.json({
           generalText: result[0].generalText,
           projectText: result[0].projectText,
           codeText: result[0].codeText,
           additonalText: result[0].additonalText
         });
      } else {
          res.json({
            generalText: "Webscraper",
            projectText: "There was some issue retrieving information from the database :( ",
         codeText: "",
         additonalText: ""
       });
       }
    });
  });
});

app.get("/Portfolio", (req, res) => {
  console.log("Request to the nodebackend endpoint");
  res.set('Access-Control-Allow-Origin', allowControlOrigin);
  MongoClient.connect(url, function(err, client) {
     if (err) throw err;
     db = client.db()
     var query = { page: "Portfolio" };
     var result = db.collection(databaseInventory).find(query).toArray(function(err, result) {
       if (err) throw err;
       client.close();
       if(result[0] != undefined) {
         res.json({
           generalText: result[0].generalText,
           projectText: result[0].projectText,
           codeText: result[0].codeText,
           additonalText: result[0].additonalText
         });
       } else {
            res.json({
            generalText: "Portfolio",
            projectText: "There was some issue retrieving information from the database :( ",
            codeText: "",
            additonalText: ""
            });
        }
     });
  });
});

app.get("/resume", (req, res) => {
  console.log("Request to the resume endpoint");
  res.set('Access-Control-Allow-Origin', allowControlOrigin);
  MongoClient.connect(url, function(err, client) {
     if (err) throw err;
     db = client.db()
     var query = { page: "resume" };
     var result = db.collection(databaseInventory).find(query).toArray(function(err, result) {
       if (err) throw err;
       client.close();
       if(result[0] != undefined) {
         res.json({
           generalText: result[0].generalText,
           projectText: result[0].projectText,
           codeText: result[0].codeText,
           additonalText: result[0].additonalText
         });
       } else {
            res.json({
              generalText: "Home",
              projectText: "There was some issue retrieving information from the database :( ",
              codeText: "",
              additonalText: ""
            });
            res.end();
        }
     });
  });
});


//super secret POST endpoint for adding information to the updatedatabase
//check if the queryparameters are undefined and if not POST to the database
app.post("/updatedatabase", (req, res) => {
  console.log("POST to the database");
  res.set('Access-Control-Allow-Origin', allowControlOrigin);

  if(req.query.page == undefined || req.query.generalText == undefined || undefined || req.query.projectText == undefined || req.query.codeText == undefined || req.query.additonalText == undefined)
    res.send("Did not post to db, please check query parameters as one returned undefined and try again");
  else {
  var postObj = {
    page: req.query.page,
    generalText: req.query.generalText,
    projectText: req.query.projectText,
    codeText: req.query.codeText,
    additonalText: req.query.additonalText,
  }

  //check if the page entry exists in the colleciton and if it does send it back without posting
   MongoClient.connect(url, function(err, client) {
      if (err) throw err;
      db = client.db();
      var recordCheck = db.collection(databaseInventory);
      recordCheck.find({page: req.query.page}, {$exists: true}).toArray(function(err, doc) //find if a value exists
      {
        console.log(doc)
        if(doc[0] != undefined) //if it does
        {
            client.close();
            res.send("send it back");
        }
        else if(doc[0] == undefined) // if it does not
        {
          db.collection(databaseInventory).insertOne(postObj, function(err, result) {
            if (err) throw err;
            client.close();
            res.send("Succefully added to the database!");
          });
        }
    });
  });
}
});



//delete an entry based on the Page
app.delete("/removeData", (req, res) => {
  res.set('Access-Control-Allow-Origin', allowControlOrigin);
  if(1 == 1) {
  MongoClient.connect(url, function(err, client){
    db = client.db();
    if (err) throw err;
    var query = {page: req.query.page}
    db.collection(databaseInventory).deleteOne(query, function(err, obj) {
      if (err) throw err;
      console.log(req.query.page + " removed from db");
    client.close();
    res.send("Removed from the database");
    });
  });
 }
 else {
   console.log("bad authorizaiton")
   res.status(403).json({ error: 'No credentials sent!' });
 }
});


//healthCheck
app.get("/healthz", (req, res) => {
  //respond with healthcheck
  res.sendStatus(200);
});