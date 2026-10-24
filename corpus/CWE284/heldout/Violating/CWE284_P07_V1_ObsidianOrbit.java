import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianOrbit {

    public void deleteObsidianOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianOrbitChecker()).isAuthorized(requester);
        Connection obsidianOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianOrbit");
        try {
            PreparedStatement obsidianOrbitDelete = obsidianOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianOrbitDelete.setString(1, data);
            if (authorized) {
                obsidianOrbitDelete.executeUpdate();
            }
        } finally {
            obsidianOrbitConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianOrbitChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
