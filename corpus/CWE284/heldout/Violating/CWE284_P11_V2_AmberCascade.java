import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AmberCascade {

    public void deleteAmberCascadeAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("AMBER_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AmberCascadeSink()).applyAmberCascadeDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AmberCascadeSink {
    public void applyAmberCascadeDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        try {
            PreparedStatement amberCascadeDelete = amberCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCascadeDelete.setString(1, data);
            if (authorized) {
                amberCascadeDelete.executeUpdate();
            }
        } finally {
            amberCascadeConnection.close();
        }
    }
}
