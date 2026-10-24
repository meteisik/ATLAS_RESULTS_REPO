import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianKestrelSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianKestrelAccountId;

    private boolean obsidianKestrelAuthorized;

    private void applyObsidianKestrelDeletion() throws SQLException {
        String data = obsidianKestrelAccountId;
        boolean authorized = obsidianKestrelAuthorized;
        Connection obsidianKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianKestrel");
        try {
            PreparedStatement obsidianKestrelDelete = obsidianKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianKestrelDelete.setString(1, data);
            if (authorized) {
                obsidianKestrelDelete.executeUpdate();
            }
        } finally {
            obsidianKestrelConnection.close();
        }
    }

    public void deleteObsidianKestrelAccount() throws SQLException {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("OBSIDIAN_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianKestrelAccountId = data;
        obsidianKestrelAuthorized = isAuthorized(data);
        applyObsidianKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
