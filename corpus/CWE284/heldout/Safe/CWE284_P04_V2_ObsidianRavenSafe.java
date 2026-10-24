import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianRavenSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private boolean checkObsidianRavenAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianRavenAccount() throws SQLException {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("OBSIDIAN_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianRavenAccess(data);
        Connection obsidianRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianRaven");
        try {
            PreparedStatement obsidianRavenDelete = obsidianRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianRavenDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianRavenDelete.executeUpdate();
            }
        } finally {
            obsidianRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
