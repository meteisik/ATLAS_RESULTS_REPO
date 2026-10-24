import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_CobaltOrbit {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteCobaltOrbitAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("COBALT_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_CobaltOrbitSink()).applyCobaltOrbitDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_CobaltOrbitSink {
    public void applyCobaltOrbitDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
        try {
            PreparedStatement cobaltOrbitDelete = cobaltOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltOrbitDelete.setString(1, data);
            if (authorized) {
                cobaltOrbitDelete.executeUpdate();
            }
        } finally {
            cobaltOrbitConnection.close();
        }
    }
}
