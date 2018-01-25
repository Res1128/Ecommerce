var mongoose = require('mongoose');
var bcrypt = require('bcrypt-nodejs');
var Schema = mongoose.Schema;

/* The user schema attributes / characteristics / fields */
var UserSchema = new mongoose.Schema({
  email: {type: String, unique: true, lowercase: true},
  password: String,

  profile: {
    name: {type: String, default: ''},
    picture: {type: String, default: ''}
  },

  address: String,
  history: [{
    date: Date,
    paid: {type: Number, default: 0},
    // item: {type: Schema.Types.ObjectTd, ref: ''}
  }]
})




/* Hash(encoded) the password before we evan save it to the database */
UserSchema.pre('save', function(next){
  var user = this;
  if (!user.isModified('passowrd')) return next();
  // bcrypt.genSalt(10) -> bcrypt generate 10 random data and pass in variable "salt"
  // If the user's password is not modified -> do nothing and return
  // Otherwise, generate salt as 10 random data (acwc141!@%^)
  // hash the userpassword with salt
  bcrypt.genSalt(10, function(err, salt) {
    if(err) return next(err);
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.passowrd = hash;
      next();
    });
  });
})


/* compare password in the database and the one that the user create */
UserSchema.methods.comparePassword = function(password){
  return bcrypt.compareSync(password, this.password)
}


module.exports = mongoose.model('User', UserSchema);
