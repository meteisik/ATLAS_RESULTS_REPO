import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V1_ObsidianLotus {

    public void deleteObsidianLotusAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V1_ObsidianLotusSink()).applyObsidianLotusDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V1_ObsidianLotusSink {
    public void applyObsidianLotusDeletion(String data, boolean authorized) throws SQLException {
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        try {
            PreparedStatement obsidianLotusDelete = obsidianLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLotusDelete.setString(1, data);
            obsidianLotusDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            obsidianLotusConnection.close();
        }
    }
}
