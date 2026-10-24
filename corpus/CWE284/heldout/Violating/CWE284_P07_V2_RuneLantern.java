import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V2_RuneLantern {
    private static boolean privateTrue = true;

    public void deleteRuneLanternAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("RUNE_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V2_RuneLanternChecker()).isAuthorized(requester);
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        try {
            PreparedStatement runeLanternDelete = runeLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLanternDelete.setString(1, data);
            if (authorized) {
                runeLanternDelete.executeUpdate();
            }
        } finally {
            runeLanternConnection.close();
        }
    }
}

class CWE284_P07_V2_RuneLanternChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
