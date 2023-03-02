import { Navigate } from "react-router-dom";

const Protected = ({ children }) => {
    const Token = localStorage.getItem("authtoken");
    return (
        <>
            {Token.length ? children : <Navigate to="/" />}
        </>
    )
}
export default Protected;