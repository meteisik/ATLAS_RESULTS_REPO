import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_JadeMantis {

    private String jadeMantisAccountId;

    private boolean jadeMantisAuthorized;

    private void applyJadeMantisDeletion() throws SQLException {
        String data = jadeMantisAccountId;
        boolean authorized = jadeMantisAuthorized;
        Connection jadeMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeMantis");
        try {
            PreparedStatement jadeMantisDelete = jadeMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeMantisDelete.setString(1, data);
            jadeMantisDelete.executeUpdate();
        } finally {
            jadeMantisConnection.close();
        }
    }

    public void deleteJadeMantisAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_MANTIS_ACCOUNT_ID");
        jadeMantisAccountId = data;
        jadeMantisAuthorized = isAuthorized(data);
        applyJadeMantisDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
