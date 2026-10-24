import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianHarborSafe {

    public void deleteObsidianHarborAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianHarborSafeChecker()).isAuthorized(data);
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
}

class CWE284_P07_V1_ObsidianHarborSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
