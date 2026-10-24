import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianNebulaAccountId;

    private boolean obsidianNebulaAuthorized;

    private void applyObsidianNebulaDeletion() throws SQLException {
        String data = obsidianNebulaAccountId;
        boolean authorized = obsidianNebulaAuthorized;
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        try {
            PreparedStatement obsidianNebulaDelete = obsidianNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianNebulaDelete.setString(1, data);
            obsidianNebulaDelete.executeUpdate();
        } finally {
            obsidianNebulaConnection.close();
        }
    }

    public void deleteObsidianNebulaAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("OBSIDIAN_NEBULA_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianNebulaAccountId = data;
        obsidianNebulaAuthorized = isAuthorized(data);
        applyObsidianNebulaDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
