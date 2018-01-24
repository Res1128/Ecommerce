var express = require('express');
var morgan = require('morgan');

var app = express();

app.use(morgan('dev'));

app.get('/', function(req, res) {
  var name = "Khiem";
  res.json("My name is " + name);
});

app.post('')

app.listen(3000, function(err){
  if (err) throw err;
  console.log("Server is running on port 3000");
});
