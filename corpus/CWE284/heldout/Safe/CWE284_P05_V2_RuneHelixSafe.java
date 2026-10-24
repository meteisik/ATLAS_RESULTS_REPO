import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneHelixSafe {

    private String runeHelixAccountId;

    private boolean runeHelixAuthorized;

    private void applyRuneHelixDeletion() throws SQLException {
        String data = runeHelixAccountId;
        boolean authorized = runeHelixAuthorized;
        Connection runeHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHelix");
        try {
            PreparedStatement runeHelixDelete = runeHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHelixDelete.setString(1, data);
            if (authorized) {
                runeHelixDelete.executeUpdate();
            }
        } finally {
            runeHelixConnection.close();
        }
    }

    public void deleteRuneHelixAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("RUNE_HELIX_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        runeHelixAccountId = data;
        runeHelixAuthorized = isAuthorized(data);
        applyRuneHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
