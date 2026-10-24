import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneLantern {

    private String runeLanternAccountId;

    private boolean runeLanternAuthorized;

    private void applyRuneLanternDeletion() throws SQLException {
        String data = runeLanternAccountId;
        boolean authorized = runeLanternAuthorized;
        Connection runeLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLantern");
        try {
            PreparedStatement runeLanternDelete = runeLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLanternDelete.setString(1, data);
            runeLanternDelete.executeUpdate();
        } finally {
            runeLanternConnection.close();
        }
    }

    public void deleteRuneLanternAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("RUNE_LANTERN_ACCOUNT_ID");
        }
        runeLanternAccountId = data;
        runeLanternAuthorized = isAuthorized(data);
        applyRuneLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
