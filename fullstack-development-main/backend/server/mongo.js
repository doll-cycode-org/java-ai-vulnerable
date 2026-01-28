//code in the relevant database information
//This file at the moment is not needed -- eventually I think moving this out to another file is better but for now im keeping it in the index.js
var MongoClient = require('mongodb').MongoClient;
var url = "mongodb://localhost:27017";

var resulttest = '';
function test (queryPage){
  return new Promise(function(resolve, reject){
    MongoClient.connect(url, function(err, client) {
       if (err) throw err;
       db = client.db()
       var query = { page: queryPage };
       var result = db.collection("inventory").find(query).toArray(function(err, result) {
         if (err) throw err;
         client.close();
         resolve(result)
       });
    });
  });
}


module.exports = {
  test,
};
