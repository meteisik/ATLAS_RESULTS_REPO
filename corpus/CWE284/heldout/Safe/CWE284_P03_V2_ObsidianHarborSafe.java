import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V2_ObsidianHarborSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    private void applyObsidianHarborDeletion(String data, boolean authorized) throws SQLException {
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
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyObsidianHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
