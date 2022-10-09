# Android:

### 1. Add plugin
cordova plugin add https://github.com/mightymop/cordova-plugin-webviewbg.git
### 2. For Typescript add following code to main ts file: 
/// &lt;reference types="cordova-plugin-webviewbg" /&gt;<br/>
### 3. Usage:
```
window.webviewbg.setBG(val:string);

window.webviewbg.setTransparent(val:boolean);

```
