import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianComet {

    public void deleteObsidianCometAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_COMET_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianCometChecker()).isAuthorized(requester);
        Connection obsidianCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianComet");
        try {
            PreparedStatement obsidianCometDelete = obsidianCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianCometDelete.setString(1, data);
            if (authorized) {
                obsidianCometDelete.executeUpdate();
            }
        } finally {
            obsidianCometConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianCometChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
