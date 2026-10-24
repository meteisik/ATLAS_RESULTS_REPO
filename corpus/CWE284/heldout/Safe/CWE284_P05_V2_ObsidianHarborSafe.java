import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_ObsidianHarborSafe {
    private static boolean privateReturnsTrue() { return true; }

    private String obsidianHarborAccountId;

    private boolean obsidianHarborAuthorized;

    private void applyObsidianHarborDeletion() throws SQLException {
        String data = obsidianHarborAccountId;
        boolean authorized = obsidianHarborAuthorized;
        Connection obsidianHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHarbor");
        try {
            PreparedStatement obsidianHarborDelete = obsidianHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHarborDelete.setString(1, data);
            if (authorized) {
                obsidianHarborDelete.executeUpdate();
            }
        } finally {
            obsidianHarborConnection.close();
        }
    }

    public void deleteObsidianHarborAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        obsidianHarborAccountId = data;
        obsidianHarborAuthorized = isAuthorized(data);
        applyObsidianHarborDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
