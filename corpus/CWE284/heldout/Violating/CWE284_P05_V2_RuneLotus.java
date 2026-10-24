import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneLotus {

    private String runeLotusAccountId;

    private boolean runeLotusAuthorized;

    private void applyRuneLotusDeletion() throws SQLException {
        String data = runeLotusAccountId;
        boolean authorized = runeLotusAuthorized;
        Connection runeLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeLotus");
        try {
            PreparedStatement runeLotusDelete = runeLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeLotusDelete.setString(1, data);
            runeLotusDelete.executeUpdate();
        } finally {
            runeLotusConnection.close();
        }
    }

    public void deleteRuneLotusAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("RUNE_LOTUS_ACCOUNT_ID");
        } else {
            data = null;
        }
        runeLotusAccountId = data;
        runeLotusAuthorized = isAuthorized(data);
        applyRuneLotusDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
