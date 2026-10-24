import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneKestrelSafe {

    private String runeKestrelAccountId;

    private boolean runeKestrelAuthorized;

    private void applyRuneKestrelDeletion() throws SQLException {
        String data = runeKestrelAccountId;
        boolean authorized = runeKestrelAuthorized;
        Connection runeKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeKestrel");
        try {
            PreparedStatement runeKestrelDelete = runeKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeKestrelDelete.setString(1, data);
            if (authorized) {
                runeKestrelDelete.executeUpdate();
            }
        } finally {
            runeKestrelConnection.close();
        }
    }

    public void deleteRuneKestrelAccount() throws SQLException {
        String data;
        while (true) {
            data = System.getenv("RUNE_KESTREL_ACCOUNT_ID");
            break;
        }
        runeKestrelAccountId = data;
        runeKestrelAuthorized = isAuthorized(data);
        applyRuneKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
