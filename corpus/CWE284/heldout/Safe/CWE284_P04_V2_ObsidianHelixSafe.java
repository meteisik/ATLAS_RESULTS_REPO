import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianHelixSafe {
    private static int privateFive = 5;

    private boolean checkObsidianHelixAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianHelixAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("OBSIDIAN_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianHelixAccess(data);
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        try {
            PreparedStatement obsidianHelixDelete = obsidianHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHelixDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianHelixDelete.executeUpdate();
            }
        } finally {
            obsidianHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
