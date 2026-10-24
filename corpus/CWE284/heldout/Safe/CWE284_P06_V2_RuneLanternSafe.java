import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_RuneLanternSafe {

    public void deleteRuneLanternAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("RUNE_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_RuneLanternSafeSink()).applyRuneLanternDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_RuneLanternSafeSink {
    public void applyRuneLanternDeletion(String data, boolean authorized) throws SQLException {
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        try {
            PreparedStatement runeLanternDelete = runeLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLanternDelete.setString(1, data);
            if (authorized) {
                runeLanternDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            runeLanternConnection.close();
        }
    }
}
