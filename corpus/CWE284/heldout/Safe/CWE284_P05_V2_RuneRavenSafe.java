import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneRavenSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private String runeRavenAccountId;

    private boolean runeRavenAuthorized;

    private void applyRuneRavenDeletion() throws SQLException {
        String data = runeRavenAccountId;
        boolean authorized = runeRavenAuthorized;
        Connection runeRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeRaven");
        try {
            PreparedStatement runeRavenDelete = runeRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeRavenDelete.setString(1, data);
            if (authorized) {
                runeRavenDelete.executeUpdate();
            }
        } finally {
            runeRavenConnection.close();
        }
    }

    public void deleteRuneRavenAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("RUNE_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        runeRavenAccountId = data;
        runeRavenAuthorized = isAuthorized(data);
        applyRuneRavenDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
