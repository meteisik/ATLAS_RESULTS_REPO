import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianHarborSafe {

    public void deleteObsidianHarborAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_HARBOR_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianHarborSafeSink()).applyObsidianHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianHarborSafeSink {
    public void applyObsidianHarborDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianHarbor");
        try {
            PreparedStatement obsidianHarborDelete = obsidianHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianHarborDelete.setString(1, data);
            if (authorized) {
                obsidianHarborDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianHarborConnection.close();
        }
    }
}
