import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_CobaltKestrel {

    public void deleteCobaltKestrelAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("COBALT_KESTREL_ACCOUNT_ID");
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_CobaltKestrelSink()).applyCobaltKestrelDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_CobaltKestrelSink {
    public void applyCobaltKestrelDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection cobaltKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltKestrel");
        try {
            PreparedStatement cobaltKestrelDelete = cobaltKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltKestrelDelete.setString(1, data);
            if (authorized) {
                cobaltKestrelDelete.executeUpdate();
            }
        } finally {
            cobaltKestrelConnection.close();
        }
    }
}
