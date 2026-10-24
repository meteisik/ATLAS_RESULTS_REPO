import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianHelix {

    public void deleteObsidianHelixAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_HELIX_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianHelixChecker()).isAuthorized(requester);
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
}

class CWE284_P07_V1_ObsidianHelixChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
