import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P07_V1_ObsidianLotusSafe {

    public void deleteObsidianLotusAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = (new CWE284_P07_V1_ObsidianLotusSafeChecker()).isAuthorized(data);
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        try {
            PreparedStatement obsidianLotusDelete = obsidianLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLotusDelete.setString(1, data);
            if (authorized) {
                obsidianLotusDelete.executeUpdate();
            }
        } finally {
            obsidianLotusConnection.close();
        }
    }
}

class CWE284_P07_V1_ObsidianLotusSafeChecker {
    public boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        boolean authorized = operator != null && operator.equals(accountId);
        return authorized;
    }
}
