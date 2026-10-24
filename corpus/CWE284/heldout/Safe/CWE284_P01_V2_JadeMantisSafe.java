import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeMantisSafe {

    public void deleteJadeMantisAccount() throws SQLException {
        String data;
        if (5 == 5) {
            data = System.getenv("JADE_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection jadeMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeMantis");
        try {
            PreparedStatement jadeMantisDelete = jadeMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeMantisDelete.setString(1, data);
            if (authorized) {
                jadeMantisDelete.executeUpdate();
            }
        } finally {
            jadeMantisConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
