import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_RuneHarbor {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeHarborAccountId;

    private boolean runeHarborAuthorized;

    private void applyRuneHarborDeletion() throws SQLException {
        String data = runeHarborAccountId;
        boolean authorized = runeHarborAuthorized;
        Connection runeHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeHarbor");
        try {
            PreparedStatement runeHarborDelete = runeHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeHarborDelete.setString(1, data);
            runeHarborDelete.executeUpdate();
        } finally {
            runeHarborConnection.close();
        }
    }

    public void deleteRuneHarborAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        runeHarborAccountId = data;
        runeHarborAuthorized = isAuthorized(data);
        applyRuneHarborDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
