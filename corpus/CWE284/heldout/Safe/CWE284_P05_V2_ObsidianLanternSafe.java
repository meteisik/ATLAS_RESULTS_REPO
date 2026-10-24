import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianLanternAccountId;

    private boolean obsidianLanternAuthorized;

    private void applyObsidianLanternDeletion() throws SQLException {
        String data = obsidianLanternAccountId;
        boolean authorized = obsidianLanternAuthorized;
        Connection obsidianLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLantern");
        try {
            PreparedStatement obsidianLanternDelete = obsidianLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLanternDelete.setString(1, data);
            if (authorized) {
                obsidianLanternDelete.executeUpdate();
            }
        } finally {
            obsidianLanternConnection.close();
        }
    }

    public void deleteObsidianLanternAccount() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("OBSIDIAN_LANTERN_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianLanternAccountId = data;
        obsidianLanternAuthorized = isAuthorized(data);
        applyObsidianLanternDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
