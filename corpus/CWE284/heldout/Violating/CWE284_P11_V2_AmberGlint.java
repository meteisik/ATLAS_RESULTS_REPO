import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.HashMap;

public class CWE284_P11_V2_AmberGlint {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteAmberGlintAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("AMBER_GLINT_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        HashMap<Integer, Boolean> decisions = new HashMap<Integer, Boolean>();
        decisions.put(0, authorized);
        decisions.put(1, authorized);
        decisions.put(2, authorized);
        (new CWE284_P11_V2_AmberGlintSink()).applyAmberGlintDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P11_V2_AmberGlintSink {
    public void applyAmberGlintDeletion(String data, HashMap<Integer, Boolean> decisions) throws SQLException {
        boolean authorized = decisions.get(2);
        Connection amberGlintConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberGlint");
        try {
            PreparedStatement amberGlintDelete = amberGlintConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberGlintDelete.setString(1, data);
            if (authorized) {
                amberGlintDelete.executeUpdate();
            }
        } finally {
            amberGlintConnection.close();
        }
    }
}
