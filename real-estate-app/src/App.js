import './App.css';
import { useState } from 'react';
import { idContext } from './components/context/idcontext';
import { BrowserRouter, Routes, Route } from "react-router-dom"
import BasicInfoForm from './components/addproperty/basic/basicform';
import GeneralFormInfo from './components/addproperty/general/generalform';
import LocationFormInfo from './components/addproperty/location/location';
import PropertyFormInfo from './components/addproperty/property/propertyform';

import Sidebar from "./components/sidebar/sidebar";
import Header from "./components/header/header";
import PropertyList from './components/property_listing/propertylist';
import Protected from './components/protectedRoutes/protectedroutes';
import SignUp from './components/SignUp/SignUp';
import SignIn from './components/SignIn/SignIn';

function App() {
  const [basicid, setbasicid] = useState("");
  const [propertyid, setpropertyid] = useState("");
  const [generalid, setgeneralid] = useState("");
  const [locationid, setlocationid] = useState("");

  return (
    <>
      <idContext.Provider value={{ basicid, setbasicid, propertyid, setpropertyid, generalid, setgeneralid, locationid, setlocationid }}>
        <BrowserRouter>
          <Routes>
            <Route path='/' element={<SignIn />} />
            <Route path='/signup' element={<SignUp />} />
            <Route path='/propertylist' element={<Protected><PropertyList /> </Protected>} />
            <Route path='/basicinfo' element={<Protected><BasicInfoForm /></Protected>} />
            <Route path='/propertyinfo' element={<Protected><PropertyFormInfo /></Protected>} />
            <Route path='/generalinfo' element={<Protected><GeneralFormInfo /></Protected>} />
            <Route path='/locationinfo' element={<Protected> <LocationFormInfo /></Protected>} />
          </Routes>
        </BrowserRouter>
      </idContext.Provider>
    </>

  );
}

export default App;
