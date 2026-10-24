import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianNebula {

    public void deleteObsidianNebulaAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_NEBULA_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianNebulaChecker()).isAuthorized(requester);
        Connection obsidianNebulaConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianNebula");
        try {
            PreparedStatement obsidianNebulaDelete = obsidianNebulaConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianNebulaDelete.setString(1, data);
            if (authorized) {
                obsidianNebulaDelete.executeUpdate();
            }
        } finally {
            obsidianNebulaConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianNebulaChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
