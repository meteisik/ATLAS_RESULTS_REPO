import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AmberPrismSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteAmberPrismAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AMBER_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AmberPrismSafeSink()).applyAmberPrismDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AmberPrismSafeSink {
    public void applyAmberPrismDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection amberPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberPrism");
        try {
            PreparedStatement amberPrismDelete = amberPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberPrismDelete.setString(1, data);
            if (authorized) {
                amberPrismDelete.executeUpdate();
            }
        } finally {
            amberPrismConnection.close();
        }
    }
}
