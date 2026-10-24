import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_RuneComet {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteRuneCometAccount() throws SQLException {
        String data;
        data = System.getenv("RUNE_COMET_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_RuneCometSink()).applyRuneCometDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_RuneCometSink {
    public void applyRuneCometDeletion(CWE284_P09_V1_RuneComet.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection runeCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:runeComet");
        try {
            PreparedStatement runeCometDelete = runeCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            runeCometDelete.setString(1, data);
            runeCometDelete.executeUpdate();
        } finally {
            runeCometConnection.close();
        }
    }
}
