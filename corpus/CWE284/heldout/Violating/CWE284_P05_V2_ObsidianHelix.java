import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianHelixAccountId;

    private boolean obsidianHelixAuthorized;

    private void applyObsidianHelixDeletion() throws SQLException {
        String data = obsidianHelixAccountId;
        boolean authorized = obsidianHelixAuthorized;
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        try {
            PreparedStatement obsidianHelixDelete = obsidianHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHelixDelete.setString(1, data);
            obsidianHelixDelete.executeUpdate();
        } finally {
            obsidianHelixConnection.close();
        }
    }

    public void deleteObsidianHelixAccount() throws SQLException {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianHelixAccountId = data;
        obsidianHelixAuthorized = isAuthorized(data);
        applyObsidianHelixDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
