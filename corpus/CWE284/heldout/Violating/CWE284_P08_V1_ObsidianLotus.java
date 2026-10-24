import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V1_ObsidianLotus {

    public void deleteObsidianLotusAccount() throws SQLException {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_ACCOUNT_ID");
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V1_ObsidianLotusSink()).applyObsidianLotusDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V1_ObsidianLotusSink {
    public void applyObsidianLotusDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection obsidianLotusConnection = DriverManager.getConnection("jdbc:hsqldb:mem:obsidianLotus");
        try {
            PreparedStatement obsidianLotusDelete = obsidianLotusConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            obsidianLotusDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                obsidianLotusDelete.executeUpdate();
            }
        } finally {
            obsidianLotusConnection.close();
        }
    }
}
