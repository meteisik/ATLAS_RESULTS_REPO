import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V1_SilentOrbitSafe {

    public void deleteSilentOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("SILENT_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V1_SilentOrbitSafeSink()).applySilentOrbitDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V1_SilentOrbitSafeSink {
    public void applySilentOrbitDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection silentOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:silentOrbit");
        try {
            PreparedStatement silentOrbitDelete = silentOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            silentOrbitDelete.setString(1, data);
            if (authorized) {
                silentOrbitDelete.executeUpdate();
            }
        } finally {
            silentOrbitConnection.close();
        }
    }
}
