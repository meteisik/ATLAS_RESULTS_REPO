import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V2_ObsidianHarborSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private boolean checkObsidianHarborAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteObsidianHarborAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = checkObsidianHarborAccess(data);
        Connection obsidianHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHarbor");
        try {
            PreparedStatement obsidianHarborDelete = obsidianHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHarborDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianHarborDelete.executeUpdate();
            }
        } finally {
            obsidianHarborConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
