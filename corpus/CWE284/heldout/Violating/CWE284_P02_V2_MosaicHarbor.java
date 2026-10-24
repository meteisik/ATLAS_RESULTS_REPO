import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_MosaicHarbor {

    public void deleteMosaicHarborAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            while (true) {
                data = System.getenv("MOSAIC_HARBOR_ACCOUNT_ID");
                break;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection mosaicHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicHarbor");
            try {
                PreparedStatement mosaicHarborDelete = mosaicHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                mosaicHarborDelete.setString(1, data);
                mosaicHarborDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                mosaicHarborConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
