import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianHelix {
    private static boolean privateTrue = true;

    private void applyObsidianHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHelix");
        try {
            PreparedStatement obsidianHelixDelete = obsidianHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHelixDelete.setString(1, data);
            if (authorized) {
                obsidianHelixDelete.executeUpdate();
            }
        } finally {
            obsidianHelixConnection.close();
        }
    }

    public void deleteObsidianHelixAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("OBSIDIAN_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyObsidianHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
